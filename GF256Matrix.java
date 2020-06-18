package org.onosproject.p4tutorial.mytunnel;
import java.util.Arrays;

public class GF256Matrix {

    private final int[][] matrix;

    /**
     * create a new matrix
     *
     * @param input initial data for the matrix
     * @param gf the mathematical field all operations will be performed in
     */
    public GF256Matrix(int input[][]) {
        this.matrix = input;
    }

    public GF256Matrix inverse() {
        return this.inverse(true);
    }

    public int[] rightMultiply(int[] vec) {
        if (vec.length != matrix.length || vec.length != matrix[0].length) { // multiplication only works if A(MxN) and B(NxO)
            throw new ArithmeticException("when matrix is MxN, vector must be Nx1");
        }

        int[] result = new int[vec.length];
        for (int i = 0; i < vec.length; i++) {
            int tmp = 0;
            for (int j = 0; j < vec.length; j++) {
                tmp = GF256.add(tmp, GF256.mult(matrix[i][j], vec[j]));
            }
            result[i] = tmp;
        }
        return result;
    }

    public int[] rightMultiplyInto(int[] result, int[] vec) {
        for (int i = 0; i < vec.length; i++) {
            int tmp = 0;
            for (int j = 0; j < vec.length; j++) {
                tmp = GF256.add(tmp, GF256.mult(matrix[i][j], vec[j]));
            }
            result[i] = tmp;
        }
        return result;
    }

    public static GF256Matrix matrixMultiply(GF256Matrix matrix1, GF256Matrix matrix2){
        if (matrix1.getNumRows() != matrix2.getNumColumn() || matrix1.getNumColumn() != matrix2.getNumRows()) {
            throw new ArithmeticException("when matrix is MxN, matrix must be NxM");
        }

        int[][] result = new int[matrix1.getNumRows()][matrix2.getNumColumn()];
        for(int i = 0; i < matrix1.getNumRows(); i++) {
            for(int j = 0; j < matrix2.getNumColumn(); j++) {
                result[i][j] = 0;
                for(int k = 0; k < matrix1.getNumColumn(); k++) {
                    result[i][j] = GF256.add(result[i][j],
                                    GF256.mult(matrix1.getElement(i, k), matrix2.getElement(k, j)));
                }
            }
        }
        return new GF256Matrix(result);
    }

    private boolean findAndSwapNonZeroInRow(final int i, final int numRows, int tmpMatrix[][], int invMatrix[][], boolean throwException) {

        boolean found = false;

        for (int j = i + 1; j < numRows && !found; j++) {
            if (tmpMatrix[j][i] != 0) {
                // found it, swap rows ...
                swapRows(tmpMatrix, i, j);
                swapRows(invMatrix, i, j);

                // ... and quit searching
                found = true;
            }
        }

        if (!found && throwException) {
            throw new RuntimeException("blub");
        }

        return found;
    }

    private GF256Matrix inverse(boolean throwException) {

        int numRows = matrix.length;

        // clone this matrix and initialize inverse matrix as unit matrix
        int[][] tmpMatrix = new int[numRows][];
        int[][] invMatrix = new int[numRows][numRows];

        for (int i = numRows - 1; i >= 0; i--) {
            tmpMatrix[i] = Arrays.copyOf(matrix[i], matrix[i].length);
            invMatrix[i][i] = 1;
        }

        // simultaneously compute Gaussian reduction of tmpMatrix and unit matrix
        for (int i = 0; i < numRows; i++) {

            // if diagonal element is zero swap a new row
            if (tmpMatrix[i][i] == 0) {
                // find a non-zero element in the same column
                boolean foundNonZero = findAndSwapNonZeroInRow(i, numRows, tmpMatrix, invMatrix, throwException);

                // if no non-zero element was found
                if (!foundNonZero) {
                    numRows--; // this will only happen in the last row
                }
            }

            // normalize i-th row
            int coef = tmpMatrix[i][i];
            int invCoef = GF256.inverse(coef);

            normalizeRow(tmpMatrix[i], invMatrix[i], invCoef);

            // subtract from all other rows
            for (int j = 0; j < numRows; j++) {
                if (j != i) {
                    coef = tmpMatrix[j][i];
                    if (coef != 0) {
                        multAndSubstract(tmpMatrix[j], tmpMatrix[i], coef);
                        multAndSubstract(invMatrix[j], invMatrix[i], coef);
                    }
                }
            }
        }

        return new GF256Matrix(invMatrix);
    }

    private void multAndSubstract(int[] row, int[] normalized, int coef) {
        for (int i = 0; i < row.length; i++) {
            row[i] = GF256.sub(row[i], GF256.mult(normalized[i], coef));
        }
    }

    public GF256Matrix inverseElimDepRows() {
        return this.inverse(false);
    }

    /*
     * Helper-methods from for Gaussian elimination
     * @author flexiprovider
     */
    private static void swapRows(int[][] matrix, int first, int second) {
        int[] tmp = matrix[first];
        matrix[first] = matrix[second];
        matrix[second] = tmp;
    }

    public int getNumRows() {
        return this.matrix.length;
    }

    public int getNumColumn() {
        return this.matrix[0].length;
    }

    private void normalizeRow(int[] tmpMatrix, int[] invMatrix, int element) {
        for (int i = tmpMatrix.length - 1; i >= 0; i--) {
            tmpMatrix[i] = GF256.mult(tmpMatrix[i], element);
            invMatrix[i] = GF256.mult(invMatrix[i], element);
        }
    }

    public int getElement(int row, int column){
        return this.matrix[row][column];
    }
}
